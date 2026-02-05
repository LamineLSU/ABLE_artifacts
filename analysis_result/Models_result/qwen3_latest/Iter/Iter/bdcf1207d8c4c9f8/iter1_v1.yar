rule CorrectedExitPattern
{
    meta:
        description = "Detects patterns leading to ExitProcess calls in a specific code sequence"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { E8 ?? ?? ?? ?? 59 }  // Call followed by pop
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? }  // Push and call sequence
        $pattern3 = { FF 15 ?? ?? ?? ?? }  // Indirect call to ExitProcess

    condition:
        any of them
}