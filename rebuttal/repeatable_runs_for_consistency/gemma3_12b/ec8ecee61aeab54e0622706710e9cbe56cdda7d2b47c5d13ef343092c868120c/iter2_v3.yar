rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 08 3D 3F 03 55 EB 8B EC EB }
        $pattern1 = { 8D 4C 24 5C E8 6D 12 00 00 EA EC DD 5C CA 03 39 2F F4 }
        $pattern2 = { 6A 01 5A 8B CE E8 12 08 00 00 00 00 00 01 EC CA 03 39 20 BF }

    condition:
        any of them
}