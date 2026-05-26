import pandas as pd
import psutil
import os
import shutil
import logging
logger = logging.getLogger("SKALD")

def split_csv_by_ram(data_dir="data"):
    """
    Detects the single CSV file inside `data_dir` and splits it into chunks
    based on ~1/4th of total system RAM.

    Strong error handling added:
    - Missing/invalid directory
    - Missing CSV
    - Multiple CSVs
    - Read failures
    - Zero-row samples
    - Tiny CSV files
    - Chunk writing errors
    """

    # --- Validate data directory ---
    if not isinstance(data_dir, str):
        logger.error("data_dir must be a string path.")
        raise TypeError("data_dir must be a string path.")
    if not os.path.isdir(data_dir):
        logger.error("Data directory does not exist: '%s'", data_dir)
        raise FileNotFoundError(f"Data directory does not exist: '{data_dir}'")

    os.makedirs("chunks", exist_ok=True)
    chunks_dir = "chunks"
    try:
        for name in os.listdir(chunks_dir):
            path = os.path.join(chunks_dir, name)
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        logger.debug("Cleared any existing contents of '%s'", chunks_dir)
    except Exception as e:
        logger.error("Failed clearing '%s': %s", chunks_dir, e)
        raise OSError(f"Failed clearing '{chunks_dir}': {e}")

    # --- Find CSV or JSON file safely ---
    try:
        all_files = os.listdir(data_dir)
        csv_files  = [f for f in all_files if f.lower().endswith(".csv")]
        json_files = [f for f in all_files if f.lower().endswith(".json")]
    except Exception as e:
        raise OSError(f"Cannot list files in '{data_dir}': {e}")

    if not csv_files and not json_files:
        raise FileNotFoundError(f"No CSV or JSON file found inside '{data_dir}'")
    if len(csv_files) + len(json_files) > 1:
        found = csv_files + json_files
        raise ValueError(
            f"More than one data file found in '{data_dir}'. Expected exactly one. Found: {found}"
        )

    # Normalise: convert JSON → CSV in-memory so the rest of the function stays unchanged
    if json_files:
        import json as _json
        json_path = os.path.join(data_dir, json_files[0])
        try:
            with open(json_path) as _f:
                raw = _json.load(_f)
        except Exception as e:
            raise RuntimeError(f"Failed reading JSON '{json_path}': {e}")
        if not isinstance(raw, list):
            raise ValueError(f"JSON file '{json_files[0]}' must contain a list of objects")
        converted_csv = os.path.join(data_dir, "_converted.csv")
        pd.DataFrame(raw).to_csv(converted_csv, index=False)
        input_csv = converted_csv
    else:
        input_csv = os.path.join(data_dir, csv_files[0])
    #print(f"Detected CSV: {input_csv}")

    # --- Detect RAM safely ---
    try:
        mem = psutil.virtual_memory()
        total_ram_bytes = mem.total
        available_ram_bytes = mem.available
        logger.info("Detected total RAM: %s bytes", total_ram_bytes)
        logger.info("Detected available RAM: %s bytes", available_ram_bytes)
    except Exception as e:
        logger.error("Failed to detect system RAM: %s", e)
        raise RuntimeError(f"Unable to detect system RAM: {e}")

    if total_ram_bytes <= 0:

        raise RuntimeError("System RAM reported as zero or negative. Cannot compute chunk size.")
    
    chunk_ram_bytes = max(total_ram_bytes // 4, 50 * 1024 * 1024)
    # ensure at least 50MB chunks

    chunk_ram_gb = chunk_ram_bytes / (1024 ** 3)

    logger.info("Splitting CSV '%s' into chunks of approx %.2f GB each", input_csv, chunk_ram_gb)

    # --- Estimate rows per chunk ---
    try:
        sample = pd.read_csv(input_csv, nrows=10000)
        #if number of rows less than 10k, then it will read all rows available in the csv
    except Exception as e:
        raise RuntimeError(f"Failed reading sample of CSV '{input_csv}': {e}")

    if sample.empty:
        raise ValueError(f"CSV '{input_csv}' appears empty. Cannot split an empty file.")

    try:
        avg_row_size = sample.memory_usage(index=True, deep=True).sum() / len(sample)
    except Exception as e:
        raise RuntimeError(f"Failed computing average row size: {e}")

    if avg_row_size <= 0:
        raise RuntimeError("Average row size computed as zero. CSV may be corrupted.")

    rows_per_chunk = int(chunk_ram_bytes / avg_row_size)
    rows_per_chunk = max(rows_per_chunk, 1000)  
    # minimum 1000 rows per chunk


    logger.info(
    "≈ %d rows per chunk (%.2f GB)",
    rows_per_chunk,
    chunk_ram_gb
)

    # --- Stream the CSV with chunking ---
    try:
        reader = pd.read_csv(input_csv, chunksize=rows_per_chunk)
    except Exception as e:
        raise RuntimeError(f"Failed creating CSV reader for '{input_csv}': {e}")

    chunk_count = 0

    for i, chunk in enumerate(reader, start=1):
        if chunk.empty:
            print(f"[WARN] Chunk {i} is empty. Skipping.")
            continue

        out_path = os.path.join("chunks", f"chunk_{i}.csv")
        try:
            chunk.to_csv(out_path, index=False)
            chunk_count += 1
        except Exception as e:
            print(f"[ERROR] Failed writing chunk {i} to '{out_path}': {e}")
            continue

    if chunk_count == 0:
        raise RuntimeError("No chunks were generated. CSV may be too small or unreadable.")

    logger.info("Successfully created %d chunks in '%s'", chunk_count, chunks_dir)
