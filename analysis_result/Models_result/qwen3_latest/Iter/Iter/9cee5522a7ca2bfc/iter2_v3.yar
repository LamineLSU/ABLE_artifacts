rule MalwareEvasionCheck
{
    meta:
        description = "Detects evasion techniques involving VirtualProtect and memory protection checks"
        cape_options = "bp0=$lea_edi_esi_minus_1000+0,action0=skip,bp1=$lea_eax_edi_plus_19f+0,action1=skip,count=0"
        author = "Cybersecurity Analyst"
        date = "2023-10-05"

    strings:
        // Pattern 1: LEA EDI, [ESI - 0x1000] followed by MOV EBX, 0x1000
        $lea_edi_esi_minus_1000 = { 8D 87 ?? ?? ?? ?? BB 00 10 00 00 }

        // Pattern 2: LEA EAX, [EDI + 0x19F] followed by CALL EBP (VirtualProtect)
        $lea_eax_edi_plus_19f = { 8D 87 9F 01 00 00 E8 ?? ?? ?? ?? }

        // Pattern 3: MOV EBP, [ESI + 0x34] followed by CALL EBP
        $mov ebp_esi_plus_34 = { 8B 45 34 E8 ?? ?? ?? ?? }

    condition:
        all of (
            $lea_edi_esi_minus_1000,
            $lea_eax_edi_plus_19f,
            $mov ebp_esi_plus_34
        )
}