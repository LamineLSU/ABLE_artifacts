rule Bypass_Sample
{
    meta:
        description = "Evasion bypass pattern based on control flow manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 59 }
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 }

    condition:
        any of them
}