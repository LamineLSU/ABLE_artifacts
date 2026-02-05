rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule - created based on sandbox analysis. Tested validation errors have been addressed."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B EC }
        $pattern1 = { FF 75 ?? C8 FF FF ?? EC }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
    condition:
        any of them
}