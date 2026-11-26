"""Entry script named by the SparkApplication's mainApplicationFile (spark-submit needs a file path)."""

import sys

from anamika_spark.run import main

sys.exit(main())
