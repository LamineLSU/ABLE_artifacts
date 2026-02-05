rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting different function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 C6 ?B ?D FF FC }  # Represents the first function call bypass
        $pattern1 = { FF 45 C3 5A 8B CE 85 }  # Represents another bypass path
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? }  # Represents a third bypass sequence

    condition:
        any of them
}