rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 D1 FF FF FF 59 FF 74 24 04 ?? ?? ?? }
        $pattern1 = { E8 F7 25 00 F7 25 00 01 ?? ?? ?? }
        $pattern2 = { E8 D1 FF FF FF FC 01 74 20 ?? ?? }

    condition:
        any of them
}