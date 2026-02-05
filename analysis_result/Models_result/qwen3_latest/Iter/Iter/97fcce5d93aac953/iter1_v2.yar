rule x86_Function_Prologue_and_Call_to_ExitProcess
{
    meta:
        description = "Detects x86 function prologue and call to ExitProcess"
        cape_options = "bp0=$prologue+0,action0=skip,bp1=$exit_call+0,action1=skip,bp2=$post_call+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"

    strings:
        // Pattern 0: Function prologue (push ebp, mov ebp, push ebp+8)
        $prologue = { 55 8B EC FF 75 08 E8 C8 FF FF }

        // Pattern 1: Call to ExitProcess (relative call)
        $exit_call = { FF 15 F8 10 41 00 }

        // Pattern 2: Post-call sequence (pop ecx, push ebp+8, call)
        $post_call = { 59 FF 75 08 FF 15 F8 10 41 00 }

    condition:
        all of them
}