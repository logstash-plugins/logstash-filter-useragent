# Logstash Plugin

[![Travis Build Status](https://travis-ci.org/logstash-plugins/logstash-filter-useragent.svg)](https://travis-ci.org/logstash-plugins/logstash-filter-useragent)

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Output

#### Mozilla/5.0 (iPad; CPU OS 9_0 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13A344 Safari/601.1

```json
{
           "name" : "Safari",
       "fullname" : "Mobile Safari",
         "vendor" : "Apple Inc.",
           "type" : "Browser (mobile)",
          "major" : "9",
          "minor" : "0",
        "version" : "9.0",
    "os" : "iOS 9 (iPad)",
      "os_vendor" : "Apple Inc.",
             "os_name" : "iOS",
         "device" : "Tablet"
}
```

#### Mozilla/5.0 (Android 4.4.2; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0

```json
{
           "name" : "Firefox",
       "fullname" : "Firefox Mobile",
         "vendor" : "Mozilla Foundation",
           "type" : "Browser (mobile)",
          "major" : "41",
          "minor" : "0",
        "version" : "41.0",
    "os" : "Android 4.x",
      "os_vendor" : "Google Inc.",
             "os_name" : "Android",
         "device" : "Mobile"
}
```

#### Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:36.0) Gecko/20100101 Firefox/36.0

```json
{
           "name" : "Firefox",
       "fullname" : "Firefox 36",
         "vendor" : "Mozilla Foundation",
           "type" : "Browser",
          "major" : "36",
          "minor" : "0",
        "version" : "36.0",
    "os" : "Ubuntu",
      "os_vendor" : "Canonical Ltd.",
             "os_name" : "Linux",
         "device" : "Computer"
}
```

## Documentation

Logstash provides infrastructure to automatically generate documentation for this plugin. We use the asciidoc format to write documentation so any comments in the source code will be first converted into asciidoc and then into html. All plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

- For formatting code or config example, you can use the asciidoc `[source,ruby]` directive
- For more asciidoc formatting tips, see the excellent reference here https://github.com/elastic/docs#asciidoc-guide

## Need Help?

Need help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed.

- Create a new plugin or clone and existing from the GitHub [logstash-plugins](https://github.com/logstash-plugins) organization. We also provide [example plugins](https://github.com/logstash-plugins?query=example).

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install`
```

- Install jar dependencies

```
bundle exec rake install_jars
```

- Run tests

```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-filter-awesome", :path => "/your/local/logstash-filter-awesome"
```
- Install plugin
```sh
# Logstash 2.3 and higher
bin/logstah-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Run Logstash with your plugin
```sh
bin/logstash -e 'filter {awesome {}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-filter-awesome.gemspec
```
- Install the plugin from the Logstash home
```sh
# Logstash 2.3 and higher
bin/logstah-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Start Logstash and proceed to test the plugin

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elastic/logstash/blob/master/CONTRIBUTING.md) file.