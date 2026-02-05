rule Bypass_ESI_Test
{
    meta:
        description = "Bypass esi test"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 74 18 83 3E 00 74 0D } // je 022484F3h, cmp dword ptr [esi], 00000000h, je 022484EDh

    condition:
        any of them
}