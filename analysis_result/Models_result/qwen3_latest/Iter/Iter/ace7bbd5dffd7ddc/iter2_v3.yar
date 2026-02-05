rule EvasionCheck
{
    meta:
        description = "Detects evasion logic via API calls, control flow manipulation, and conditional jumps."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    
    strings:
        $pattern0 = { FF D2 5E 5E 5D C3 }
        $pattern1 = { E8 ?? 0A 00 00 50 }
        $pattern2 = { 93 7C E1 C2 ?? 80 }
    
    condition:
        any of ($pattern0, $pattern1, $pattern2)
}