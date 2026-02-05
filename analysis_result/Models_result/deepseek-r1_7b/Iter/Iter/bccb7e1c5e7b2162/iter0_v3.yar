rule Bypass_Sample {
       meta:
           description = "Evasion bypass: Skipping direct call to target address"
           cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

       strings:
           $pattern2 = { 59 ?? FF 75 08 E8 C8 ?? ?? B0 AC } // Skipping a direct call instruction
       condition:
           any of them
   }