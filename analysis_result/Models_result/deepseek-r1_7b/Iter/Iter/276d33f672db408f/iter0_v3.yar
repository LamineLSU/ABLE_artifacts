rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting memory accesses and conditional jumps"
        cape_options = "bp0=$pattern0+0,bp1=$pattern1+0,bp2=$pattern2+0,count=3"

    strings:
        $pattern0 = { 45 6A 0F 84 8B 45 02 }
        $pattern1 = { 5A 8B CE E8 0F ?? 5A 8B 49 EC }
        $pattern2 = { 6A 1C 51 0F 8B 45 03 ?? }

    condition:
        any of them
}