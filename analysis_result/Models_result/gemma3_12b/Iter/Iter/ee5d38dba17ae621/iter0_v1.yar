rule Bypass_ESI_LEA
{
    meta:
        description = "Evasion bypass: Skip LEA instruction"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 6A 00 56 8D B0 A0 0C 00 00 }

    condition:
        any of them
}