import importlib
import os

class PluginManager:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.plugins = []
        self.load_plugins()

    def load_plugins(self):
        plugin_dir = self.config.get('plugin_directory', 'plugins')
        for filename in os.listdir(plugin_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]
                try:
                    module = importlib.import_module(f'{plugin_dir}.{module_name}')
                    if hasattr(module, 'run'):
                        self.plugins.append(module)
                        self.logger.info(f"Loaded plugin: {module_name}")
                except Exception as e:
                    self.logger.error(f"Error loading plugin {module_name}: {e}")

    def run_plugins(self, url, session):
        results = []
        for plugin in self.plugins:
            try:
                plugin_result = plugin.run(url, session, self.config)
                results.append(plugin_result)
            except Exception as e:
                self.logger.error(f"Error running plugin {plugin.__name__}: {e}")
        return results
