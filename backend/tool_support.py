"""
Tool Calling support for OpenAI-compatible API.

Strategy:
  1. Strict system prompt forces the AI to output ONLY raw JSON when it wants
     to call a tool — no preamble, no markdown fences.
  2. When tools are present, we ALWAYS buffer the full response first (no
     partial streaming) so we can reliably decide: tool-call JSON or plain text.
  3. If the full response contains a valid tool_calls JSON anywhere (even buried
     in preamble text), we extract it with regex.  This handles the hallucination
     case where the AI writes "Sure! Let me read that file: {…}".
  4. Once decided, we replay the result back to the caller in proper OpenAI
     chunk format (streaming) or as a single block (non-streaming).
"""
import json
import re
import uuid

# ---------------------------------------------------------------------------
# 1. System prompt generation
# ---------------------------------------------------------------------------

_TOOL_SYSTEM_TEMPLATE = """\
You have access to the following tools.  When you decide to use one or more \
tools, you MUST respond with **ONLY** a single raw JSON object — no \
explanation, no markdown fences, no text before or after.  The JSON must \
match this schema exactly:

{{"tool_calls": [{{"id": "call_<random_id>", "type": "function", "function": {{"name": "<tool_name>", "arguments": {{"<arg_name>": "<arg_value>"}}}}}}]}}

CRITICAL RULES:
- The "arguments" value MUST be a raw JSON object containing the parameters.
- Output NOTHING except the JSON object when calling a tool.
- If you do NOT need a tool, reply normally in natural language.
- NEVER wrap the JSON in ```json``` or any markdown code block.
- You can call MULTIPLE tools at once by adding more items to the "tool_calls" array.
- ALWAYS use FORWARD SLASHES (/) for file paths, even on Windows. NEVER use backslashes (\\\\).

PROACTIVE BEHAVIOR (YOUR #1 PRIORITY):
- On your VERY FIRST response, you MUST IMMEDIATELY call tools to read files. \
Do NOT write any text first. Do NOT explain what you plan to do. Do NOT ask \
the user for permission. Just call the tools RIGHT NOW.
- You are an AUTONOMOUS agent. You have the tools. USE THEM without hesitation.
- NEVER say "I need to read files first" or "send me a command to read". \
You already HAVE the command — it's the read_file tool. CALL IT.
- NEVER say "I haven't read any files yet". Instead, READ THEM.
- NEVER ask the user to tell you to read files. Just DO IT.
- If the user asks about the codebase, your response must be a tool_calls \
JSON — not text explaining that you need to read files.
- You may ONLY call tools that are listed below. Do NOT invent or hallucinate \
tool names. If a tool is not listed below, it does NOT exist. For example, \
do NOT call manage_todo_list, list_dir, file_search, or any other tool that \
is not explicitly listed in the Available tools section.

THOROUGHNESS RULES (MANDATORY — NEVER SKIP):
- You MUST read EVERY SINGLE file in the project — no exceptions.
- This includes ALL file types: .py, .ts, .tsx, .js, .json, .css, .html, \
__init__.py, Dockerfile, requirements.txt, README.md, .env, .bat, .sh, \
.txt config files — EVERYTHING.
- Do NOT stop after reading a few files to summarize. Keep calling tools \
until you have read ALL files.  Only give your final answer AFTER reading \
everything.
- NEVER say "I haven't read X yet" or "let me know if you want me to read \
more".  Just READ IT immediately without asking.
- If a directory has 20 files, you must read all 20.  If it has 50, read 50.
- Batch as many read operations as possible into a SINGLE tool_calls response \
to minimize round-trips.
- If you are unsure whether a file is relevant, READ IT.  It is always \
better to read too much than too little.

ANTI-HALLUCINATION RULES:
- You do NOT have any subagents or assistants.
- You MUST perform all file reading yourself by explicitly calling the tools.
- Do NOT claim to have explored the codebase if you did not explicitly call \
the read tools for EVERY file.
- Do NOT hallucinate file contents or summarize without reading.
- NEVER guess what a file contains based on its name alone.

Available tools:
{tool_list}"""


def build_tool_system_prompt(tools: list) -> str:
    if not tools:
        return ""
    lines = []
    for t in tools:
        if t.get("type") != "function":
            continue
        f = t.get("function", {})
        name = f.get("name", "?")
        desc = f.get("description", "")
        params = json.dumps(f.get("parameters", {}), ensure_ascii=False)
        lines.append(f"- **{name}**: {desc}\n  Parameters: {params}")
    return _TOOL_SYSTEM_TEMPLATE.format(tool_list="\n".join(lines))


# ---------------------------------------------------------------------------
# 2. Message pre-processing (inject prompt, convert tool results)
# ---------------------------------------------------------------------------

def inject_tools_and_results(msgs: list, tools: list) -> list:
    """
    1. Prepend (or merge with existing) system prompt that teaches tool usage.
    2. Convert role="tool" messages into role="user" so the plain-text backend
       can forward them.
    3. Convert role="assistant" messages that contain tool_calls into the
       text representation the AI originally produced.
    """
    if not tools:
        return msgs

    tool_prompt = build_tool_system_prompt(tools)
    new_msgs: list[dict] = []

    # Check if first message is already a system prompt — merge if so
    start = 0
    if msgs and msgs[0].get("role") == "system":
        merged = msgs[0]["content"] + "\n\n" + tool_prompt
        new_msgs.append({"role": "system", "content": merged})
        start = 1
    else:
        new_msgs.append({"role": "system", "content": tool_prompt})

    for m in msgs[start:]:
        role = m.get("role", "user")

        if role == "tool":
            # IDE is returning a tool execution result
            content = m.get("content", "")
            tid = m.get("tool_call_id", "?")
            new_msgs.append({
                "role": "user",
                "content": f"[Tool Result id={tid}]\n{content}"
            })

        elif role == "assistant" and m.get("tool_calls"):
            # Previous assistant turn that contained tool calls —
            # reconstruct the JSON the AI would have emitted
            tc_json = json.dumps({"tool_calls": m["tool_calls"]}, ensure_ascii=False)
            new_msgs.append({"role": "assistant", "content": tc_json})

        else:
            new_msgs.append(m)

    return new_msgs


# ---------------------------------------------------------------------------
# 3. Response parsing — extract tool calls from AI text
# ---------------------------------------------------------------------------

# Regex: find a JSON object containing "tool_calls" anywhere in the text
_TOOL_JSON_RE = re.compile(
    r'\{\s*"tool_calls"\s*:\s*\[.*?\]\s*\}',
    re.DOTALL,
)


def _extract_tool_calls(text: str, valid_tools: set | None = None) -> list[dict] | None:
    """
    Scan *text* for a JSON blob matching {"tool_calls": [...]}.
    Returns the formatted list of tool calls, or None if not found.
    """
    # Step 1: strip markdown fences if present
    cleaned = text.strip()
    if cleaned.startswith("```"):
        # Remove opening fence (```json or ```)
        first_nl = cleaned.find("\n")
        if first_nl != -1:
            cleaned = cleaned[first_nl + 1:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

    # Helper to fix common Claude hallucination: unescaped Windows paths like c:\Users
    def fix_json(s: str) -> str:
        # Replaces any backslash that isn't part of a valid JSON escape sequence with a double backslash
        return re.sub(r'\\(?=[^"\\/bfnrtu])', r'\\\\', s)

    # Step 2: try to parse the whole thing as JSON first (fast path)
    try:
        data = json.loads(cleaned)
        if "tool_calls" in data:
            return _format_tool_calls(data["tool_calls"], valid_tools)
    except (json.JSONDecodeError, ValueError):
        try:
            data = json.loads(fix_json(cleaned))
            if "tool_calls" in data:
                return _format_tool_calls(data["tool_calls"], valid_tools)
        except (json.JSONDecodeError, ValueError):
            pass

    # Step 3: Extract {"tool_calls": [...]} even if severely truncated
    all_calls = []
    
    # Find all occurrences of {"tool_calls"
    start_idx = 0
    while True:
        idx = text.find('"tool_calls"', start_idx)
        if idx == -1:
            break
            
        # Find the opening brace before "tool_calls"
        brace_idx = text.rfind('{', start_idx, idx)
        if brace_idx == -1:
            start_idx = idx + 12
            continue
            
        raw_match = text[brace_idx:].strip()
        parsed = False
        
        # Try appending common missing closing braces to fix truncated JSON
        for fix_suffix in ["", "}", "]}", "}]}", "]}}", "} ]}", "]}}]", "]}}]}"]:
            attempt = raw_match + fix_suffix
            try:
                data = json.loads(attempt)
                all_calls.extend(data.get("tool_calls", []))
                parsed = True
                break
            except (json.JSONDecodeError, ValueError):
                try:
                    data = json.loads(fix_json(attempt))
                    all_calls.extend(data.get("tool_calls", []))
                    parsed = True
                    break
                except (json.JSONDecodeError, ValueError):
                    pass
        
        if not parsed:
            # Last ditch: try to extract individual tool call objects using a looser regex
            inner_matches = re.findall(r'\{\s*"id"\s*:\s*"[^"]+",\s*"type"\s*:\s*"function",\s*"function"\s*:\s*\{.*?\}\s*\}', raw_match, re.DOTALL)
            for inner in inner_matches:
                try:
                    all_calls.append(json.loads(inner))
                except:
                    pass
                    
        start_idx = idx + 12

    if all_calls:
        return _format_tool_calls(all_calls, valid_tools)

    return None


def _format_tool_calls(raw_calls: list, valid_tools: set | None = None) -> list[dict]:
    """Normalise tool calls into OpenAI format, filtering out hallucinated tools."""
    out = []
    for i, tc in enumerate(raw_calls):
        func = tc.get("function", {})
        name = func.get("name", "")
        # Skip hallucinated tool names that the IDE doesn't know about
        if valid_tools and name not in valid_tools:
            continue
        args = func.get("arguments", "")
        # If AI returned arguments as a dict instead of a string, fix it
        if isinstance(args, dict):
            args = json.dumps(args, ensure_ascii=False)
        out.append({
            "index": len(out),
            "id": tc.get("id", f"call_{uuid.uuid4().hex[:12]}"),
            "type": "function",
            "function": {
                "name": name,
                "arguments": args,
            },
        })
    return out


# ---------------------------------------------------------------------------
# 4. Stream interceptor
# ---------------------------------------------------------------------------

class ToolCallStreamInterceptor:
    """
    ALWAYS buffers the entire response. Raw JSON never leaks to screen.
      - TOOL_DEBUG=True  (dev): show pretty summary + tool_calls
      - TOOL_DEBUG=False (prod): show only tool_calls (or text if no tools)
    """

    def __init__(self, valid_tools: set | None = None):
        from worker import config as _cfg
        self._debug = getattr(_cfg, "TOOL_DEBUG", False)
        self.buffer = ""
        self._valid_tools = valid_tools  # set of real tool names from IDE

    def feed(self, delta: str) -> None:
        self.buffer += delta

    def get_passthrough(self) -> list[dict]:
        return []

    @staticmethod
    def _pretty_summary(tool_calls: list) -> str:
        """Build a human-readable summary."""
        read_files = []
        other_calls = []

        for tc in tool_calls:
            func = tc.get("function", {})
            name = func.get("name", "?")
            args_raw = func.get("arguments", "{}")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except (json.JSONDecodeError, ValueError):
                args = {}

            if "read" in name.lower() or "file" in name.lower():
                fp = args.get("filePath", args.get("path", "?"))
                basename = fp.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                start = args.get("startLine", "")
                end = args.get("endLine", "")
                if start and end:
                    read_files.append(f"`{basename}` #L{start}-{end}")
                else:
                    read_files.append(f"`{basename}`")
            else:
                other_calls.append(f"`{name}`")

        lines = []
        if read_files:
            lines.append(f"Reading {len(read_files)} file{'s' if len(read_files) > 1 else ''}: {', '.join(read_files)}")
        if other_calls:
            lines.append(f"Calling: {', '.join(other_calls)}")
        return "\n".join(lines) if lines else "Executing tool calls..."

    def finish(self) -> list[dict]:
        if not self.buffer:
            return []

        tool_calls = _extract_tool_calls(self.buffer, self._valid_tools)
        chunks = []

        if tool_calls:
            if self._debug:
                chunks.append({
                    "choices": [{
                        "index": 0,
                        "delta": {"content": self._pretty_summary(tool_calls)},
                        "finish_reason": None,
                    }]
                })
            chunks.append({
                "choices": [{
                    "index": 0,
                    "delta": {"tool_calls": tool_calls},
                    "finish_reason": "tool_calls",
                }]
            })
        else:
            chunks.append({
                "choices": [{
                    "index": 0,
                    "delta": {"content": self.buffer},
                    "finish_reason": None,
                }]
            })

        return chunks
