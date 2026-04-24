Goal - For each sample, determine whether the generated YARA rule likely caused meaningful bypass-related execution progression, rather than incidental behavior change.

1. Sample Selection - Select 42 successful samples from the 264 using stratified sampling:

   • 15 samples from iteration~0 successes  
   • 15 samples from iteration~1 successes  
   • 12 samples from iteration~2 successes  (due to the iteration 2 just have total 13 samples success)

Within each group, include different malware families when possible.

Validation report

| Sample | Iter | Rule Action | Checkpoint Type | New Behavior | Validation Label in AI Sandbox |
|---|---|---|---|---|---|
| hash prefix | 0/1/2 | skip/wret/etc. | time/API/env/exit | signatures/artifacts | Yes/No/inconclusive |