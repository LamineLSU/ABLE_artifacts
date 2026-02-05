rule Bypass_PUSH
{
    meta:
        description = "Bypass PUSH EBP instruction"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 C8 FF FF FF 59 }

    condition:
        any of them
}