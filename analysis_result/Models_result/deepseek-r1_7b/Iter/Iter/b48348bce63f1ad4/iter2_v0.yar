rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting function calls and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? ?? 59 ?? }
        $pattern1 = { FF 75 08 ?? ?? ?? ?? F8 C1 FF FF FF ?? }
        $pattern2 = { 6A 00 83 C1 ?? ?? ?? ?? FF 75 08 ?? }

    condition:
        any of them
}