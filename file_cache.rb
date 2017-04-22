require "yaml"
require "fileutils"

class FileCache
  def initialize(path)
    FileUtils.mkdir_p(path) unless File.exist?(path)
    @path = path
  end

  def []=(id, data)
    IO.write(File.join(@path, id), data)
  end

  def [](id)
    file = File.join(@path, id)
    File.read(file) if File.exist?(file)
  end

  def delete(id)
    file = File.join(@path, id)
    FileUtils.rm(file) if File.exist?(file)
  end
end
