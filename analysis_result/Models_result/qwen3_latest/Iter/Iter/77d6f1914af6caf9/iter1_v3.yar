rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 56 57 FF 15 ?? ?? ?? ?? }  // PUSH EBX/ESI/EDI + CALL
        $pattern1 = { 74 03 75 01 E8 ?? ?? ?? ?? }   // JZ/JNZ + CALL (conditional check)
        $pattern2 = { FF 15 ?? ?? ?? ?? }            // CALL to API (OpenEventA/CreateEventA)

    condition:
        any of them
}