rule Malware_Evasion_Bypass
{
    meta:
        description = "Malware Evasion Bypass Rule"
        author = "Bard"
        date = "2024-02-29"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 48 83 EC 28 53 48 8B C3 }
        $pattern1 = { 55 48 89 C8 E8 ?? ?? ?? ?? 8B }
        $pattern2 = { 48 83 EC 20 48 8D 0D ?? ?? ?? ?? }

    condition:
        any of them
}