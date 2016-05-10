The PRIMO tool for static Intent resolution and probabilistic value inference.

# Installation

```shell
$ sudo python setup.py build
$ sudo python setup.py install
```

The script can be run directly from the top-level directory afterwards.

For further instructions, please see http://siis.cse.psu.edu/primo

# Usage


```shell
$ primo --protodir ic3-output/ --dumpintentlinks links.blp

$ mkdir stats

$ make_plots_and_stats --input links.blp --out stats/
2016-05-10 09:20:34,538 [root] [INFO ]  Loading file links.blp.
2016-05-10 09:20:34,541 [root] [INFO ]  Loaded 35375 Intent links.
2016-05-10 09:20:34,541 [root] [INFO ]  Plotting probability distribution CDF.
2016-05-10 09:20:35,669 [root] [INFO ]  Finished plotting probability distribution CDF.
2016-05-10 09:20:35,669 [root] [INFO ]  Plotting probability distribution histogram.
2016-05-10 09:20:36,632 [root] [INFO ]  Finished plotting probability distribution histogram.
2016-05-10 09:20:36,632 [root] [INFO ]  Plotting probability distribution by inter/intra app Intent.
2016-05-10 09:20:41,133 [root] [INFO ]  Finished plotting histograms.
2016-05-10 09:20:41,133 [root] [INFO ]  Computing Intent connectivities.
2016-05-10 09:20:41,158 [root] [INFO ]  Finished computing Intent connectivities from Intent links.
2016-05-10 09:20:41,159 [root] [INFO ]  Computing connectivity CDFs.
2016-05-10 09:20:41,731 [root] [INFO ]  Plotting link CDF.
2016-05-10 09:20:42,272 [root] [INFO ]  Finished plotting link CDF.
```
