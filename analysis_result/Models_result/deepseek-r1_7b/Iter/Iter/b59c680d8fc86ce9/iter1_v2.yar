rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using identified vulnerable call points"
        cape_options = "bp0=E8F7250000,bp1=C1E8A801,bp2=E80B000000"
        count = 0

    strings:
        $pattern0 = { 20 }
        $pattern1 = { 20 }
        $pattern2 = { 20 }

    condition:
        any of them
}