rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 C0 FB FB FF FF 8B 45 ?? }
        $pattern1 = { 68 E8 03 00 00 8D 85 14 FC FB FF FF 53 50 E8 1B 26 02 00 }
        $pattern2 = { 8D 75 08 E8 21 B1 FF FF 8B 4D FC 5F 5E 33 CD 5B E8 00 B7 01 00 }

    condition:
        any of them
}