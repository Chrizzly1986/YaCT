/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Detects code being injected into the YaCT process at start-up.
 *
 * <p>YaCT's modules keep keys away from other code in the process (strong
 * encapsulation). The JVM offers ways around that, and they can be switched on
 * from outside, e.g. by malware setting an environment variable that every
 * Java program reads: Java agents ({@code -javaagent}), {@code --add-opens}
 * and similar options, an alternative security configuration or system class
 * loader. YaCT refuses to start when it finds any of them.
 *
 * <p>This is a tripwire, not a sandbox: code that already runs as the user
 * can also log keystrokes. It closes the cheap, silent routes.
 */
final class RuntimeChecks
{
	/** JVM options (and their system-property forms) that let other code reach into YaCT. */
	private static final List<String> FORBIDDEN_OPTIONS = List.of(
			"-javaagent", "-agentlib", "-agentpath", "-Xbootclasspath",
			"--patch-module", "--add-opens", "--add-exports", "--add-reads", "--upgrade-module-path",
			"-Djdk.module.patch", "-Djdk.module.addopens", "-Djdk.module.addexports", "-Djdk.module.addreads",
			"-Djdk.module.upgrade.path", "-Djava.system.class.loader", "-Djava.security.properties",
			"-Djava.security.policy", "-Djava.security.manager", "-XX:+EnableDynamicAgentLoading",
			"-Djdk.attach.allowAttachSelf");

	/** Additionally forbidden in the packaged application, where all modules are linked into the runtime. */
	private static final List<String> FORBIDDEN_WHEN_PACKAGED = List.of(
			"--module-path", "-p", "-Djdk.module.path", "--add-modules", "-Djdk.module.addmods", "-cp", "-classpath",
			"--class-path", "-Djava.class.path", "-Djava.library.path");

	/** Environment variables the JVM or the java launcher read options from; checked for the options above. */
	private static final List<String> FORBIDDEN_ENV = List.of("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS");

	private RuntimeChecks()
	{
	}

	/** Problems in the current process; empty if none. */
	static List<String> current()
	{
		boolean packaged = Boolean.getBoolean("yact.packaged");
		Set<String> modules = ModuleLayer.boot().modules().stream().map(Module::getName).collect(Collectors.toSet());
		return problems(ManagementFactory.getRuntimeMXBean().getInputArguments(), System.getenv(),
				System.getProperty("java.class.path", ""), modules, packaged);
	}

	/** True if a developer explicitly allowed an unchecked start (never in the packaged application). */
	static boolean developerOverride(List<String> jvmArgs, boolean packaged)
	{
		return !packaged && jvmArgs.contains("-Dyact.dev=true");
	}

	static List<String> problems(List<String> jvmArgs, Map<String, String> env, String classPath, Set<String> modules,
			boolean packaged)
	{
		List<String> problems = new ArrayList<>();
		for (String arg : jvmArgs)
		{
			if (matches(arg, FORBIDDEN_OPTIONS))
				problems.add("JVM option " + arg);
			else if (packaged && matches(arg, FORBIDDEN_WHEN_PACKAGED) && !arg.startsWith("-Djava.library.path=" + javaHomeLib()))
				problems.add("JVM option " + arg);
		}
		// Such variables are often set for harmless reasons (proxy, trust store); only dangerous content counts.
		for (String name : FORBIDDEN_ENV)
		{
			String value = env.get(name);
			if (value == null)
				continue;
			for (String token : value.trim().split("\\s+"))
				if (matches(token, FORBIDDEN_OPTIONS) || (packaged && matches(token, FORBIDDEN_WHEN_PACKAGED)))
					problems.add("environment variable " + name + ": " + token);
		}
		if (packaged)
		{
			if (!classPath.isBlank())
				problems.add("class path " + classPath);
			for (String m : modules)
				if (!(m.startsWith("java.") || m.startsWith("jdk.") || m.startsWith("javafx.") || m.startsWith("yact.")
						|| m.equals("org.bouncycastle.provider")))
					problems.add("unexpected module " + m);
		}
		return problems;
	}

	private static boolean matches(String arg, List<String> options)
	{
		for (String o : options)
			if (arg.equals(o) || arg.startsWith(o + "=") || arg.startsWith(o + ":")
					|| (o.startsWith("-D") && arg.startsWith(o)) || (o.startsWith("-X") && arg.startsWith(o)))
				return true;
		return false;
	}

	private static String javaHomeLib()
	{
		return System.getProperty("java.home", "\u0000");
	}
}
