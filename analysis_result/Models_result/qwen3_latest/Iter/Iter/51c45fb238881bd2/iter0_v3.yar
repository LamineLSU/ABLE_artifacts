rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 85 ?? ?? ?? ?? FF 96 ?? ?? ?? ?? }  // Test EAX, JNE, CALL [esi+000000B0h]
        $pattern1 = { 83 3D ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? }  // CMP dword [00491000h], JNE, CALL 004012C4h
        $pattern2 = { 80 7B 28 02 75 0E E8 ?? ?? ?? ?? 83 3D ?? }  // CMP byte [ebx+28h], JNE, CALL, CMP dword [ebx]

    condition:
        any of them
}