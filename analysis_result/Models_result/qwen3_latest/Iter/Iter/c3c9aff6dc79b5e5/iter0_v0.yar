rule MaliciousPattern
{
    meta:
        description = "Identifies a suspicious pattern of function calls and register manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 FF 15 ?? ?? ?? ?? }
        $pattern1 = { FF 35 D4 B0 41 00 FF 15 ?? ?? ?? ?? }
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}