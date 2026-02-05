rule Bypass_Sample_1
{
    meta:
        description = "Bypass ExitProcess Trace 1"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 00 40 E7 F6 E8 C8 FF FF FF FF 59 FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}