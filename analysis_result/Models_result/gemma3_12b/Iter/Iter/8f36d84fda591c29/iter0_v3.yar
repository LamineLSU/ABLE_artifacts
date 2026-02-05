rule Bypass_Sample_CALL_Early
{
    meta:
        description = "Bypass early CALL instruction"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}