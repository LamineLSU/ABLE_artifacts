rule Evasion_Bypass
{
    meta:
        description = "Detects evasion techniques involving function calls and exit mechanisms"
        cape_options = "bp0=$exit_call_1+0,action0=skip,bp1=$func_call_1+0,action1=skip,bp2=$exit_call_2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-15"

    strings:
        // Pattern 0: Exit call with preceding stack adjustments
        $exit_call_1 = { 83 C4 14 52 FF D0 } // add esp, 14h; push edx; call eax

        // Pattern 1: Function call with register manipulation
        $func_call_1 = { 8B 06 50 E8 ?? ?? ?? ?? } // mov eax, [esi]; push eax; call (offset)

        // Pattern 2: Exit call with ebp-based register access
        $exit_call_2 = { 8B 55 0C 52 FF D0 } // mov edx, [ebp+0Ch]; push edx; call eax

    condition:
        (all of ($exit_call_1, $func_call_1, $exit_call_2))
}