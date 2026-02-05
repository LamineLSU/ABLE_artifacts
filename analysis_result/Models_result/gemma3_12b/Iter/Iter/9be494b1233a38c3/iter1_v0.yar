rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 C0 FB FF FF FF 8B 45 ?? }
        $pattern1 = { E8 1B 26 02 00 68 E8 03 00 00 8D 85 14 FC FF FF FF }
        $pattern2 = { 6A E8 00 B7 01 00 5B 33 CD 5E }

    condition:
        any of them
}