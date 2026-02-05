rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // CALL + TEST EAX + JE/JNE
        $pattern1 = { B9 ?? ?? ?? ?? 8D 4D FC EB 03 8B 45 FC }  // CMP+JECXZ+MOV (concrete bytes from trace)
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 }  // CMP+EAX/JNE+MOV (concrete comparison value)

    condition:
        any of them
}