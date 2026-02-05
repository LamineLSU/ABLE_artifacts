rule ConditionalExitDetection
{
    meta:
        description = "Detects conditional exit based on VirtualAllocExNuma return value."
        author = "Your Name"
        date = "2025-04-01"

    strings:
        $call_virtualalloc = /FF 15 ?? ?? ?? ??/  // Call to VirtualAllocExNuma
        $cmp_and_jne = /83 7D FC 00 75 08/        // Compare and jump if not zero
        $call_exitprocess = /FF 15 88 7C 42 00/   // Call to ExitProcess

    condition:
        all of them
}