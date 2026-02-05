rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0:0x0041A61D:0x0041A61D, bp1=$pattern1:0x0041A621:0x0041A621, bp2=$pattern2:0x0041A622:0x0041A622"

    strings:
        $pattern0 = { 52 50 51 FF D2 }
        $pattern1 = { 5D C3 }
        $pattern2 = { BE 46 61 68 FE }

    condition:
        all of them
}