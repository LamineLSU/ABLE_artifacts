rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 88 A0 1D 01 ?? ?? ?? ?? }
        $pattern1 = { FF 15 2C A1 1D 01 ?? ?? ?? ?? }
        $pattern2 = { E8 C8 FF FF FF 59 FF 75 08 }

    condition:
        any of them
}