rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 EC 18 } // CALL instruction with JMP/LOOP
        $pattern1 = { B9 ?? ?? ?? ?? EB ?? } // MOV EAX,[ADDR] followed by JMP
        $pattern2 = { 3D ?? ?? ?? ?? 74 ?? } // CMP EAX,IMM32 followed by JNZ

    condition:
        any of them
}