rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 8B 45 08 8B 48 14 56 6A 35 51 8D B0 98 0C 00 00 }  // Heap allocation + stack setup
        $pattern1 = { E2 6B ?? ?? FF D0 5E 5D C3 55 8B EC 8B 45 0C 8B 48 04 }  // Loop + ExitProcess call + stack setup
        $pattern2 = { 69 97 ?? ?? ?? ?? ?? 55 8B EC 8B 45 08 8D B0 A0 0C 00 00 }  // imul + stack setup + heap allocation

    condition:
        any of them
}