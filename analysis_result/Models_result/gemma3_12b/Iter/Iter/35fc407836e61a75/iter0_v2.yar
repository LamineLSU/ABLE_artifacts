rule Bypass_Sample_1
{
    meta:
        description = "Bypass CALL 0041B0ACh"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 FF 15 AC B0 41 00 } //PUSH EBP, MOV EBP, ESP, PUSH dword ptr [ebp+08], CALL 0041B0ACh (16 bytes)

    condition:
        any of them
}