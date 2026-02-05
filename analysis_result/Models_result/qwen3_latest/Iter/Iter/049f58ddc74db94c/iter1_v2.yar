rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? }  // TEST EAX, JE (early check)
        $pattern1 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }  // PUSH/POP + CALL (obfuscation)
        $pattern2 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF 03 C3 }  // MOV + LEA + ADD (data manipulation)

    condition:
        any of them
}