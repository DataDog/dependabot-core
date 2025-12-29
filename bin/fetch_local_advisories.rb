#!/usr/bin/env ruby
# frozen_string_literal: true

# ============================================================================
# FETCH LOCAL ADVISORIES - Standalone Advisory Database Query Tool
# ============================================================================
#
# This script clones GitHub's Advisory Database and queries it for security
# advisories affecting dependencies in your repository.
#
# Supported ecosystems: gradle, cargo, go_modules
#
# Usage:
#   ruby bin/fetch_local_advisories.rb /path/to/repo
#
# Output:
#   JSON array of advisories, one per dependency file, ready to pass to runner.rb
#
# Example:
#   ruby bin/fetch_local_advisories.rb ~/myrepo > advisories.json
#   SECURITY_ADVISORIES=$(cat advisories.json | jq -r '.[0].advisories | @json') \
#     ruby bin/runner.rb go_modules ~/myrepo --dir /path/to/go.mod
#
# ============================================================================

require "json"
require "fileutils"
require "optparse"

# ============================================================================
# LOCAL ADVISORY DATABASE
# ============================================================================

module LocalAdvisoryDatabase
  GITHUB_ADVISORY_REPO = "https://github.com/github/advisory-database.git"
  DEFAULT_DB_PATH = File.expand_path("~/.dependabot/advisory-database")
  SUPPORTED_ECOSYSTEMS = ["Go", "crates.io", "Maven"].freeze

  class << self
    attr_reader :advisory_index

    def db_path
      @db_path ||= ENV.fetch("ADVISORY_DB_PATH", DEFAULT_DB_PATH)
    end

    def clone_database!
      if Dir.exist?(db_path)
        puts "ℹ️  Advisory database already exists at #{db_path}"
        puts "   To re-clone, delete it first: rm -rf #{db_path}"
        return
      end

      puts "📥 Cloning GitHub Advisory Database..."
      puts "   This may take a few minutes..."

      FileUtils.mkdir_p(File.dirname(db_path))

      # Clone with depth=1 to save space and time
      system("git clone --depth 1 #{GITHUB_ADVISORY_REPO} #{db_path}", exception: true)

      puts "✅ Advisory database cloned successfully to #{db_path}"
    rescue StandardError => e
      abort("❌ Failed to clone advisory database: #{e.message}")
    end

    # Load all advisories into memory and build an index
    def load_advisories!
      return @advisory_index if @advisory_index

      puts "\n📚 Loading advisories into memory..."
      start_time = Time.now

      advisories_path = File.join(db_path, "advisories", "github-reviewed")
      abort("❌ Advisory database not found at #{advisories_path}") unless Dir.exist?(advisories_path)

      @advisory_index = Hash.new { |h, k| h[k] = {} }
      total_files = 0
      loaded_advisories = 0

      # Find all JSON files
      json_files = Dir.glob(File.join(advisories_path, "**", "*.json"))
      total_files = json_files.size

      puts "   Found #{total_files} advisory files"
      puts "   Filtering for ecosystems: #{SUPPORTED_ECOSYSTEMS.join(', ')}"

      json_files.each_with_index do |file, idx|
        if (idx + 1) % 5000 == 0
          puts "   Progress: #{idx + 1}/#{total_files} files processed..."
        end

        begin
          data = JSON.parse(File.read(file))
          affected = data["affected"] || []

          affected.each do |affected_pkg|
            pkg_data = affected_pkg["package"] || {}
            ecosystem = pkg_data["ecosystem"]
            package_name = pkg_data["name"]

            # Only index supported ecosystems
            next unless SUPPORTED_ECOSYSTEMS.include?(ecosystem)
            next unless package_name

            # Initialize array for this package if needed
            @advisory_index[ecosystem][package_name.downcase] ||= []

            # Store the parsed advisory
            advisory = parse_advisory_for_package(data, ecosystem, package_name, affected_pkg)
            @advisory_index[ecosystem][package_name.downcase] << advisory if advisory
            loaded_advisories += 1
          end
        rescue StandardError => e
          # Skip malformed files
        end
      end

      elapsed = Time.now - start_time
      puts "   ✅ Loaded #{loaded_advisories} advisories for #{SUPPORTED_ECOSYSTEMS.join(', ')} in %.1f seconds" % elapsed
      puts "   Memory index ready for fast lookups\n\n"

      @advisory_index
    end

    # Fetch advisories for a given ecosystem and package name (fast lookup)
    def fetch_advisories(ecosystem:, package_name:)
      load_advisories! unless @advisory_index

      github_ecosystem = map_ecosystem(ecosystem)
      @advisory_index.dig(github_ecosystem, package_name.downcase) || []
    end

    private

    def map_ecosystem(package_manager)
      case package_manager
      when "go_modules", "gomod"
        "Go"
      when "cargo"
        "crates.io"
      when "maven", "gradle"
        "Maven"
      else
        package_manager
      end
    end

    def parse_advisory_for_package(data, ecosystem, package_name, affected_entry)
      return nil unless affected_entry

      # Extract version ranges
      ranges = affected_entry["ranges"] || []
      vulnerable_versions = []

      ranges.each do |range|
        events = range["events"] || []
        events.each do |event|
          if event["introduced"]
            introduced = event["introduced"]
            vulnerable_versions << ">= #{introduced}" unless introduced == "0"
          end
          if event["fixed"]
            vulnerable_versions << "< #{event['fixed']}"
          end
        end
      end

      severity = data["severity"] || data.dig("database_specific", "severity") || "UNKNOWN"

      {
        "dependency-name" => package_name,
        "affected-versions" => vulnerable_versions,
        "patched-versions" => [],
        "unaffected-versions" => [],
        "ghsa-id" => data["id"],
        "cve-id" => data.dig("aliases", 0),
        "severity" => severity,
        "title" => data["summary"],
        "description" => data["details"]
      }
    end
  end
end

# ============================================================================
# DEPENDENCY FILE SCANNER
# ============================================================================

module DependencyScanner
  SUPPORTED_ECOSYSTEMS = {
    "go_modules" => {
      patterns: ["**/go.mod"],
      parser: :parse_go_mod
    },
    "cargo" => {
      patterns: ["**/Cargo.toml"],
      parser: :parse_cargo_toml
    },
    "gradle" => {
      patterns: ["**/build.gradle", "**/build.gradle.kts"],
      parser: :parse_gradle
    }
  }

  class << self
    def find_dependency_files(repo_path)
      files = []

      SUPPORTED_ECOSYSTEMS.each do |ecosystem, config|
        config[:patterns].each do |pattern|
          Dir.glob(File.join(repo_path, pattern)).each do |file_path|
            relative_path = file_path.sub("#{repo_path}/", "")
            directory = "/" + File.dirname(relative_path)
            directory = "/" if directory == "/."

            files << {
              ecosystem: ecosystem,
              file_path: file_path,
              relative_path: relative_path,
              directory: directory,
              parser: config[:parser]
            }
          end
        end
      end

      files
    end

    def extract_packages(file_info)
      send(file_info[:parser], file_info[:file_path])
    rescue StandardError => e
      puts "⚠️  Failed to parse #{file_info[:relative_path]}: #{e.message}"
      []
    end

    private

    def parse_go_mod(file_path)
      packages = []
      content = File.read(file_path)

      # Extract require blocks
      content.scan(/require\s+\(([^)]+)\)/m) do |block|
        block[0].scan(/^\s*([^\s]+)\s+v?[\d.]+/) do |match|
          packages << match[0].strip
        end
      end

      # Extract single require lines
      content.scan(/^\s*require\s+([^\s]+)\s+v?[\d.]+/) do |match|
        packages << match[0].strip
      end

      packages.uniq
    end

    def parse_cargo_toml(file_path)
      packages = []
      content = File.read(file_path)
      in_dependencies = false

      content.each_line do |line|
        if line.match?(/^\[(dependencies|dev-dependencies|build-dependencies)\]/)
          in_dependencies = true
          next
        end

        if line.match?(/^\[/)
          in_dependencies = false
        end

        if in_dependencies && line.match?(/^([a-zA-Z0-9_-]+)\s*=/)
          packages << line.match(/^([a-zA-Z0-9_-]+)\s*=/)[1]
        end
      end

      packages.uniq
    end

    def parse_gradle(file_path)
      packages = []
      content = File.read(file_path)

      # Extract Maven coordinates from various dependency declarations
      patterns = [
        /(?:implementation|api|compile|testImplementation|testCompile|runtimeOnly)\s*[("']\s*([^:]+:[^:]+):/,
        /(?:implementation|api|compile|testImplementation|testCompile|runtimeOnly)\s*\(\s*[("']([^:]+:[^:]+):/
      ]

      patterns.each do |pattern|
        content.scan(pattern) do |match|
          # Convert group:artifact to package name (e.g., "org.springframework:spring-core")
          packages << match[0].strip
        end
      end

      packages.uniq
    end
  end
end

# ============================================================================
# MAIN SCRIPT
# ============================================================================

def main
  options = { format: :json }

  OptionParser.new do |opts|
    opts.banner = "Usage: ruby bin/fetch_local_advisories.rb [options] REPO_PATH"

    opts.on("--format FORMAT", "Output format: json (default) or commands") do |v|
      options[:format] = v.to_sym
    end

    opts.on("--clone-only", "Only clone the database, don't scan") do
      options[:clone_only] = true
    end

    opts.on("-h", "--help", "Show this help message") do
      puts opts
      exit
    end
  end.parse!

  # Clone database
  LocalAdvisoryDatabase.clone_database!

  if options[:clone_only]
    puts "\n✅ Database ready. Run without --clone-only to scan for advisories."
    exit 0
  end

  # Get repo path
  repo_path = ARGV[0]
  unless repo_path
    abort("Error: Please provide a repository path\nUsage: ruby bin/fetch_local_advisories.rb REPO_PATH")
  end

  unless Dir.exist?(repo_path)
    abort("Error: Repository path does not exist: #{repo_path}")
  end

  repo_path = File.expand_path(repo_path)

  puts "\n🔍 Scanning for dependency files in #{repo_path}..."

  dependency_files = DependencyScanner.find_dependency_files(repo_path)

  if dependency_files.empty?
    puts "No dependency files found for supported ecosystems (go_modules, cargo, gradle)"
    exit 0
  end

  puts "Found #{dependency_files.count} dependency file(s)\n\n"

  results = []

  dependency_files.each do |file_info|
    puts "📄 #{file_info[:relative_path]}"
    puts "   Ecosystem: #{file_info[:ecosystem]}"
    puts "   Directory: #{file_info[:directory]}"

    packages = DependencyScanner.extract_packages(file_info)
    puts "   Found #{packages.count} packages"

    advisories = []
    packages.each do |package|
      pkg_advisories = LocalAdvisoryDatabase.fetch_advisories(
        ecosystem: file_info[:ecosystem],
        package_name: package
      )

      if pkg_advisories.any?
        advisories.concat(pkg_advisories)
        puts "   ⚠️  #{package}: #{pkg_advisories.count} advisory(ies)"
      end
    end

    results << {
      ecosystem: file_info[:ecosystem],
      directory: file_info[:directory],
      file: file_info[:relative_path],
      package_count: packages.count,
      advisory_count: advisories.count,
      advisories: advisories
    }

    puts "   Total: #{advisories.count} advisory(ies)\n\n"
  end

  # Output results
  puts "=" * 80
  puts "RESULTS"
  puts "=" * 80
  puts

  if options[:format] == :commands
    output_commands(results, repo_path)
  else
    output_json(results)
  end
end

def output_json(results)
  puts JSON.pretty_generate(results)
end

def output_commands(results, repo_path)
  puts "# Run these commands to update dependencies with security advisories:\n\n"

  results.each do |result|
    next if result[:advisory_count].zero?

    advisories_json = JSON.generate(result[:advisories])

    puts "# #{result[:file]} (#{result[:advisory_count]} advisories)"
    puts "SECURITY_ADVISORIES='#{advisories_json}' \\"
    puts "  ruby bin/runner.rb #{result[:ecosystem]} #{repo_path} \\"
    puts "  --dir #{result[:directory]} \\"
    puts "  --security-updates-only"
    puts
  end

  if results.none? { |r| r[:advisory_count] > 0 }
    puts "# No advisories found - no commands to run"
  end
end

# Run the script
main if __FILE__ == $PROGRAM_NAME
