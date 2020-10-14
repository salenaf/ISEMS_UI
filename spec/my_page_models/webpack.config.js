const path = require("path");
const webpack = require("webpack");

const ExtractTextPlugin = require("extract-text-webpack-plugin");

let bootstrapPath = path.join(__dirname, "node_modules/bootstrap/dist/css");

module.exports = {
    //место откуда берутся js файлы
    context: __dirname + "/js",

    //точки входа
    entry: {
        vendors: [
            "react",
            "reactDom",
            "reactBootstrap",
            "bootstrap",
            "select2",
            //            "select2Full",
            "jquery",
        ],
        header: "./pages/header.jsx",
        headerMenu: "./pages/headerMenu.jsx",
        organizationAndSources: "./pages/settings/organizations_and_sources/organizationAndSources.jsx",
        common: "./common.js",
        styles: "./styles.js",
    },

    output: {
        path: path.resolve(__dirname, "dist"),
        //интернет путь до указанной директории
        publicPath: "/dist/",

        //шаблоны файлов, применяется при сборке основных файлов
        filename: "[name].js",

        //применяется при сборке файлов через require.ensure
        chunkFilename: "[id].js",

        //экспорт каждой точки входа должен попадать в переменную с соответствующем именем
        library: "[name]"
    },

    resolve: {
        modules: ["node_modules", bootstrapPath],
        extensions: [".js", ".jsx", ".css"],
        alias: {
            "react": "react",
            "reactDom": "react-dom",
            "reactBootstrap": "react-bootstrap/dist/react-bootstrap.min.js",
            "bootstrap": "bootstrap/dist/js/bootstrap.min.js",
            //"select2": "select2/dist/js/select2.js",
            "select2": "select2/dist/js/select2.full.min.js",
            "jquery": "jquery/dist/jquery.min.js",
        }
    },

    resolveLoader: {
        modules: ["node_modules"],
        extensions: [".js"],
        moduleExtensions: ["*-loader"]
    },

    plugins: [
        //не собирать если есть ошибки
        new webpack.NoEmitOnErrorsPlugin(),

        //выносит все стили в отдельные файлы
        new ExtractTextPlugin("css/[id]_[name].css", { allChunks: true }),

        new webpack.optimize.OccurrenceOrderPlugin(true)
    ],

    module: {
        rules: [{
                test: /\.js|jsx?$/, // определяем тип файлов
                exclude: /node_modules/, // исключаем из обработки папку node_modules
                loader: "babel-loader", // определяем загрузчик
                options: {
                    presets: ["@babel/preset-env", "@babel/preset-react"] // используемые плагины
                }
            },
            {
                test: /\.js$/,
                exclude: /node_modules/,
                use: ["babel-loader"] //, 'eslint-loader']
            },
            {
                test: /\.css$/,
                use: ExtractTextPlugin.extract({
                    fallback: "style-loader",
                    use: ["css-loader"]
                })
            },
            {
                test: /\.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)(\?.*)?$/,
                include: /\/node_modules\//,
                use: [{
                    loader: "file-loader",
                    options: {
                        name: "[path][name].[ext]",
                        publicPath: "dist/",
                    },
                }, ],
            },
            {
                test: /\.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)(\?.*)?$/,
                exclude: /\/node_modules\//,
                use: [{
                    loader: "file-loader",
                    options: {
                        name: "[path][name].[ext]",
                        publicPath: "dist/",
                    },
                }, ],
            },
            {
                test: /bootstrap-tokenfield\/dist\/bootstrap-tokenfield\.min\.js/,
                loader: "imports-loader?this=>window&exports=>false&define=>false"
            },
            /*            {
                                                    test: /\.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)(\?.*)?$/,
                                                    include: /\/node_modules\//,
                                                    loader: 'file-loader?name=[1]&regExp=node_modules/(.*)&publicPath=dist/'
                                                },
                                                {
                                                    test: /\.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)(\?.*)?$/,
                                                    exclude: /\/node_modules\//,
                                                    loader: 'file-loader?name=[path][name].[ext]&publicPath=dist/'
                                                },*/
            {
                test: /\.ejs$/,
                loader: "ejs-loader"
            }
        ]
    }
};