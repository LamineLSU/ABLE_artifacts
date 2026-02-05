rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 7D E8 14 0F 82 BE 20 00 00 6A 00 FF 96 ?? ?? ?? ?? }
        $pattern1 = { A1 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? }
        $pattern2 = { 80 7B 28 02 75 0E }

    condition:
        any of them
}