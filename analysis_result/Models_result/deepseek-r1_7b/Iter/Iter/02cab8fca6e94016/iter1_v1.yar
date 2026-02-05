rule Bypass_Sample
{
    meta:
        description = "Evasion bypass using function call and conditional jump bypass paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 6A 5B 8B CE 85 C0 74 12 ?? }
        $pattern1 = { 6A 40 8B CE E8 C8 ?? }
        $pattern2 = { 6A 5B EB A1 01 E8 25 ?? }

    condition:
        any of them
}