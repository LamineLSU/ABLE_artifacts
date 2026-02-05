rule EvasionCheck
{
    meta:
        description = "Detects evasion check logic leading to ExitProcess call"
        cape_options = "bp0=$push_eax_call+0,action0=skip,bp1=$push_edx_call+0,action1=skip,bp2=$lea_esi+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-05"

    strings:
        // Pattern 0: Push EAX followed by call to 0041EB37h
        $push_eax_call = { 50 E8 74 0A 00 00 }

        // Pattern 1: Push EDX followed by call to EAX (ExitProcess)
        $push_edx_call = { 52 FF D0 }

        // Pattern 2: LEA ESI, [EAX+00000CA0h]
        $lea_esi = { 8D B0 A0 0C 00 00 }

    condition:
        all of (
            $push_eax_call or $push_edx_call or $lea_esi
        )
}