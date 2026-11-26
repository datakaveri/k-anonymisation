"""Multi-table bundles: SKALD's sheet joins, on Spark.

SKALD's command line merges a multi-sheet workbook into one table before anything else
(SKALD/src/pipeline/multitabular.rs), anonymises that table, and with `restore_sheets` splits the
result back into one sheet per input sheet. This module does the same over a bundle's tables, so the
output equals the CLI's for the same input. What it mirrors, and where:

  merge_excel_sheets      one table: as is. `sheet_joins`: explicit joins. Else the same columns in every
                          table: stack them. Else: join on the shared columns, left.
  merge_two               pandas `merge` semantics: one row per matching pair, unmatched rows kept per
                          `how` (left, right, inner, outer, cross), output columns = the left's, then the
                          right's non-key columns; a name in both gets `_x` (left) / `_y` (right).
  build_restore_plan      which original sheet and column each merged column came from.
  write_restored_workbook the split: per sheet, its own columns under their original names, rows
                          de-duplicated on the anonymised values, first occurrence first.

Row order is what makes a distributed join reproducible. The CLI's join is a loop over left rows in
file order, taking the matching right rows in file order, then appending the unmatched right rows in
file order. Every table row carries an id (part number << 32 | row in part) that encodes file order;
each join step sorts by (left id, right id) with NULLs last (the appended unmatched right rows have no
left id) and then numbers the result again, so the next step sees the same order the CLI would.

What is NOT distributed, and the limits:
  * The sort after each join is a global sort (a shuffle), not a driver step; nothing here collects rows.
  * Two tables with NO shared column are joined by the CLI by row position ("horizontal concat"). That
    needs a global row number and is refused (INVALID_INPUT) here rather than approximated.
  * The CLI splits the final CSV line by line, so a quoted value with a line break breaks its restore;
    here such a value is simply kept intact, which is the behaviour the CLI's restore intends.

Column names inside Spark are positional (`c0`, `c1`, ...): a header may contain dots, spaces or
anything else, and Spark would try to interpret it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .errors import JobError

ID = "__id"
ALLOWED_HOW = ("left", "right", "inner", "outer", "cross")
_SPARK_HOW = {"left": "left", "right": "right", "inner": "inner", "outer": "full_outer"}


@dataclass(frozen=True)
class SheetJoin:
    left: str
    right: str
    on: Tuple[str, ...]
    how: str = "left"


def parse_sheet_joins(section: Dict[str, Any]) -> List[SheetJoin]:
    """`sheet_joins` from the config section, validated as SKALD's parse_sheet_joins does."""
    raw = section.get("sheet_joins")
    if not isinstance(raw, list):
        return []
    out = []
    for entry in raw:
        if not isinstance(entry, dict) or not isinstance(entry.get("left"), str) or not isinstance(entry.get("right"), str):
            raise JobError("INVALID_INPUT")
        on = entry.get("on")
        cols = [on] if isinstance(on, str) else [c for c in on if isinstance(c, str)] if isinstance(on, list) else []
        how = entry.get("how", "left")
        if not cols or how not in ALLOWED_HOW:
            raise JobError("INVALID_INPUT")
        out.append(SheetJoin(entry["left"], entry["right"], tuple(cols), how))
    return out


# ---------------------------------------------------------------- the plan (names only, no data)
@dataclass
class Step:
    """One join, resolved against the columns the two frames have at that point."""

    left: str
    right: str
    how: str
    on: Tuple[str, ...]
    left_cols: List[str]
    right_cols: List[str]
    out_cols: List[str]
    left_on: List[int]
    right_on: List[int]
    right_nonkey: List[int]


@dataclass
class SheetColumns:
    """One original sheet's slice of the merged table: (merged column, original column) pairs."""

    sheet: str
    columns: List[Tuple[str, str]]


@dataclass
class JoinPlan:
    mode: str                                   # "single" | "joins" | "concat" | "auto"
    root: str                                   # the table the merged result is named after
    columns: List[str]                          # merged header
    steps: List[Step] = field(default_factory=list)
    origins: List[Tuple[str, str]] = field(default_factory=list)   # per merged column: (sheet, original name)
    restore: Optional[List[SheetColumns]] = None                   # None: no split is possible (CLI: no plan)
    tables: List[Tuple[str, List[str]]] = field(default_factory=list)  # input (name, header), in order

    def key_name(self, merged: str) -> str:
        """The contract's per-job key name: "<table>/<column>" of the column's origin when the bundle has
        several tables, the bare column otherwise. A join column shared by two sheets is one merged
        column and so one key, named after the sheet it first appears in (the left one)."""
        if len(self.tables) == 1:
            return merged
        i = self.columns.index(merged)
        sheet, original = self.origins[i]
        return f"{sheet}/{original}"

    def resolve(self, table: Optional[str], column: str) -> Optional[str]:
        """The merged column a manifest entry's (table, column) denotes, or None.

        Entries name the table and column as the user knows them. A column of the merged table matches
        itself, and an original column maps through the restore plan (so a saved key for
        `visits/id` finds the merged `id`). Ambiguous names are left to the caller to refuse."""
        if table is None or len(self.tables) == 1:
            return column if column in self.columns else None
        for sc in self.restore or []:
            if sc.sheet == table:
                for merged, original in sc.columns:
                    if original == column:
                        return merged
        for i, (sheet, original) in enumerate(self.origins):
            if sheet == table and original == column:
                return self.columns[i]
        return None


def _merge_cols(left: List[str], right: List[str], on: Tuple[str, ...], how: str):
    """merge_two's column layout: (out columns, left_on idx, right_on idx, right non-key idx)."""
    if how == "cross":
        rn, ln = set(right), set(left)
        return ([f"{c}_x" if c in rn else c for c in left] + [f"{c}_y" if c in ln else c for c in right],
                [], [], list(range(len(right))))
    left_on = [left.index(c) for c in on]
    right_on = [right.index(c) for c in on]
    nonkey = [i for i in range(len(right)) if i not in right_on]
    nk_names = {right[i] for i in nonkey}
    ln = set(left)
    out = [f"{c}_x" if c in nk_names else c for c in left]
    out += [f"{right[i]}_y" if right[i] in ln else right[i] for i in nonkey]
    return out, left_on, right_on, nonkey


def plan_tables(tables: List[Tuple[str, List[str]]], joins: List[SheetJoin]) -> JoinPlan:
    """The merge SKALD would do for these tables (names and columns only)."""
    names = [n for n, _ in tables]
    if len(set(names)) != len(names) or any(len(set(h)) != len(h) for _, h in tables):
        raise JobError("INVALID_INPUT")  # duplicate table or column names: the CLI's result is not well defined
    if len(tables) == 1:
        name, header = tables[0]
        return JoinPlan("single", name, list(header), [], [(name, c) for c in header],
                        [SheetColumns(name, [(c, c) for c in header])], list(tables))
    if joins:
        return _plan_joins(tables, joins)
    if all(sorted(h) == sorted(tables[0][1]) for _, h in tables):
        header = list(tables[0][1])
        return JoinPlan("concat", names[0], header, [], [(names[0], c) for c in header], None, list(tables))
    return _plan_auto(tables)


def _plan_joins(tables, joins: List[SheetJoin]) -> JoinPlan:
    frames: Dict[str, Tuple[List[str], List[Tuple[str, str]]]] = {n: (list(h), [(n, c) for c in h]) for n, h in tables}
    steps, root = [], None
    for j in joins:
        if j.left not in frames or j.right not in frames:
            raise JobError("INVALID_INPUT")
        (lc, lo), (rc, ro) = frames[j.left], frames[j.right]
        if any(c not in lc or c not in rc for c in j.on):
            raise JobError("INVALID_INPUT")
        out, lon, ron, nonkey = _merge_cols(lc, rc, j.on, j.how)
        steps.append(Step(j.left, j.right, j.how, j.on, lc, rc, out, lon, ron, nonkey))
        # Provenance as merge_two_tracked keeps it: the left's, then the right's non-key columns.
        frames[j.left] = (out, list(lo) + [ro[i] for i in nonkey])
        root = root or j.left
    cols, origins = frames[root]
    plan = JoinPlan("joins", root, cols, steps, origins, None, list(tables))
    plan.restore = _restore_plan(tables, cols, origins)
    return plan


def _plan_auto(tables) -> JoinPlan:
    """CLI's auto_join_sheets: left-join each next table on the columns it shares with the result so far."""
    (name, header) = tables[0]
    cols, origins, steps = list(header), [(name, c) for c in header], []
    for rname, rcols in tables[1:]:
        common = tuple(c for c in cols if c in rcols)
        if not common:
            raise JobError("INVALID_INPUT")  # the CLI pastes these side by side by row position; not reproducible here
        out, lon, ron, nonkey = _merge_cols(cols, rcols, common, "left")
        steps.append(Step(name, rname, "left", common, list(cols), list(rcols), out, lon, ron, nonkey))
        ro = [(rname, c) for c in rcols]
        origins, cols = origins + [ro[i] for i in nonkey], out
    return JoinPlan("auto", name, cols, steps, origins, None, list(tables))


def _restore_plan(tables, columns: List[str], origins: List[Tuple[str, str]]) -> List[SheetColumns]:
    """SKALD's build_restore_plan: walk each ORIGINAL sheet's columns in its own order; a column is found by
    its origin, or failing that by being a merged column of the same name (the join key of the right
    side, whose own provenance the join drops). A sheet with no column left out is omitted."""
    lookup = {(s, c): columns[i] for i, (s, c) in enumerate(origins)}
    finals = set(columns)
    out = []
    for name, header in tables:
        cols = []
        for c in header:
            final = lookup.get((name, c))
            if final is None and c in finals:
                final = c
            if final is not None:
                cols.append((final, c))
        if cols:
            out.append(SheetColumns(name, cols))
    return out


# ---------------------------------------------------------------- Spark
def _fill(F, col, alias):
    return F.coalesce(col, F.lit("")).alias(alias)


def join_frames(spark, plan: JoinPlan, frames: Dict[str, Any], storage):
    """Execute `plan` over `frames` ({table: DataFrame c0..cN, __id}); returns the merged DataFrame
    (c0..cM, __id) in the CLI's row order, persisted. Frames the steps replace are not touched."""
    from pyspark.sql import functions as F  # noqa: PLC0415

    if plan.mode == "single":
        return frames[plan.root]
    if plan.mode == "concat":
        return _stack(F, plan, frames)

    current = dict(frames)
    for st in plan.steps:
        left, right = current[st.left], current[st.right]
        lsel = [F.col(f"c{i}").alias(f"l{i}") for i in range(len(st.left_cols))] + [F.col(ID).alias("__lid")]
        rsel = [F.col(f"c{i}").alias(f"r{i}") for i in range(len(st.right_cols))] + [F.col(ID).alias("__rid")]
        L, R = left.select(*lsel), right.select(*rsel)
        if st.how == "cross":
            joined = L.crossJoin(R)
        else:
            cond = None
            for li, ri in zip(st.left_on, st.right_on):
                eq = F.col(f"l{li}") == F.col(f"r{ri}")
                cond = eq if cond is None else cond & eq
            joined = L.join(R, cond, _SPARK_HOW[st.how])
        out = []
        for i in range(len(st.left_cols)):
            if i in st.left_on and st.how in ("right", "outer"):
                # A right row with no left match carries its own key value into the left's key column.
                ri = st.right_on[st.left_on.index(i)]
                out.append(F.coalesce(F.col(f"l{i}"), F.col(f"r{ri}"), F.lit("")).alias(f"c{i}"))
            else:
                out.append(_fill(F, F.col(f"l{i}"), f"c{i}"))
        for k, ri in enumerate(st.right_nonkey):
            out.append(_fill(F, F.col(f"r{ri}"), f"c{len(st.left_cols) + k}"))
        # Left rows in file order, each with its right matches in file order; right rows no left row
        # matched (no left id) last, in file order. That is merge_two's loop.
        ordered = joined.select(*out, F.col("__lid"), F.col("__rid")).orderBy(
            F.col("__lid").asc_nulls_last(), F.col("__rid").asc_nulls_last())
        merged = ordered.withColumn(ID, F.monotonically_increasing_id()).drop("__lid", "__rid").persist(storage)
        current[st.left] = merged
    return current[plan.root]


def _stack(F, plan: JoinPlan, frames: Dict[str, Any]):
    """Same columns in every table: rows of the first table, then the second, ... (CLI's vertical_concat),
    aligned by column NAME as it does when the order differs."""
    parts = []
    for t, (name, header) in enumerate(plan.tables):
        pos = {c: i for i, c in enumerate(header)}
        sel = [F.col(f"c{pos[c]}").alias(f"c{i}") for i, c in enumerate(plan.columns)]
        parts.append(frames[name].select(*sel, (F.col(ID) + F.lit(t << 52)).alias(ID)))
    out = parts[0]
    for p in parts[1:]:
        out = out.unionByName(p)
    return out


def dedupe_sheet(F, df, columns: List[Tuple[str, str]], names: List[str]):
    """One sheet of the split: its columns (merged name -> original name), distinct rows, each at its first
    occurrence. `names` are the columns of the anonymised table `df` holds (c0.. in that order); a sheet
    column the anonymisation removed reads as empty, as in SKALD. Returns (c0.., __id) with __id the
    first occurrence."""
    sel = [F.col(f"c{names.index(m)}").alias(f"c{k}") if m in names else F.lit("").alias(f"c{k}")
           for k, (m, _) in enumerate(columns)]
    proj = df.select(*sel, F.col(ID))
    return proj.groupBy(*[f"c{k}" for k in range(len(columns))]).agg(F.min(ID).alias(ID))
