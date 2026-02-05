rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 EB 8B EC EB 8B 45 08 EA DD EB 08 8B 88 14 0A 00 00 EC DD EA 00 00 0A 14 }
        $pattern1 = { 8B 16 ED DD 50 EA 51 EC FF D2 CA ED }
        $pattern2 = { 6A 3C 00 00 00 3C BF 00 D3 C5 21 ED 21 C5 D3 00 28 B1 67 BD 06 55 EC 55 06 BD 67 }

    condition:
        any of them
}