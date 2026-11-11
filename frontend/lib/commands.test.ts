import { describe, expect, it } from "vitest";
import { cliCommands } from "./commands";

describe("cliCommands", () => {
  it("pins the selected version and includes what capm run requires", () => {
    const c = cliCommands("alice", "pr-reviewer", "0.1.0");
    expect(c.inspect).toBe("capm inspect alice/pr-reviewer@0.1.0");
    expect(c.run).toBe(
      "capm run alice/pr-reviewer@0.1.0 --model-url <your-endpoint> --allow-unenforced-egress",
    );
  });

  it("uses a yanked or older selected version, never latest", () => {
    expect(cliCommands("a", "b", "1.0.0-rc.1").run).toContain("a/b@1.0.0-rc.1 ");
  });

  it("strips characters that could break the shown shell command", () => {
    const c = cliCommands("a;rm -rf ~", "b`x`", "1.0.0$(id)");
    expect(c.run.split(" ")).toHaveLength(6);
    expect(c.run.split(" ")[2]).toBe("arm-rf/bx@1.0.0id");
  });
});
