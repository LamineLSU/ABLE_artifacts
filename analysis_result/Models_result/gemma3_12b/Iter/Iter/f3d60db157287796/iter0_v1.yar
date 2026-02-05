rule MalwareEvasionBypass
{
    meta:
        description = "Malware Evasion Bypass"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Bard"
        date = "2023-10-27"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 8B CE E8 25 05 00 00 85 C0 0F 84 33 FD FF FF FF }
        $pattern2 = { 8B 45 04 5F 5E 33 CD 5B E8 57 26 00 00 }

    condition:
        any of them
}