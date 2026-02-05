rule EvasionPatterns
{
    meta:
        description = "Detects evasion patterns involving function calls and conditional checks"
        cape_options = "bp0=$p1+0,action0=skip,bp1=$p2+0,action1=skip,bp2=$p3+0,action2=skip,count=0"
    
    strings:
        $p1 = { 68 00 00 00 00 E8 ?? ?? ?? ?? }
        $p2 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $p3 = { 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}