rule FunctionCallPatterns
{
    meta:
        description = "Detects function call patterns with offset and memory addressing"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
    
    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 50 53 57 56 }
        $pattern2 = { FF 15 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        all of them
}