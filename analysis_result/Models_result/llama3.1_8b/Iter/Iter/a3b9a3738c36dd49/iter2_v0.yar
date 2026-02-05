rule Bypass_Sample_Evolved_3
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern2+0,action0=skip"

    strings:
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        $pattern2
}